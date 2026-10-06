-- Banco NOVO: execute este arquivo uma vez. Sem Supabase Auth.
begin;
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create table public.licenses (
 id uuid primary key default gen_random_uuid(),
 key_hash text unique not null,
 user_id uuid unique not null default gen_random_uuid(),
 email text unique not null check(email=lower(btrim(email)) and position('@' in email)>1),
 enabled boolean not null default true,
 expires_at timestamptz,
 active_session text,
 session_hash text unique,
 session_expires_at timestamptz,
 lease_until timestamptz,
 daily_ai_limit integer not null default 30 check(daily_ai_limit between 0 and 10000),
 created_at timestamptz not null default now()
);
create table public.ai_usage (
 user_id uuid not null references public.licenses(user_id) on delete cascade,
 day date not null,calls integer not null default 0,
 primary key(user_id,day)
);
create table public.records (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.licenses(user_id) on delete cascade,
 kind text not null check(kind in ('edital','plan','booklet','board','question','simulation','attempt','essay')),
 payload jsonb not null check(jsonb_typeof(payload)='object' and octet_length(payload::text)<=4000000),
 created_at timestamptz not null default now()
);
create index records_owner_kind on public.records(user_id,kind,created_at,id);
alter table public.licenses enable row level security;
alter table public.ai_usage enable row level security;
alter table public.records enable row level security;
-- Nenhum cliente anônimo/autenticado recebe acesso direto às tabelas.
revoke all on public.licenses,public.ai_usage,public.records from anon,authenticated;

create schema if not exists private;
revoke all on schema private from public,anon,authenticated;

create or replace function public.license_login(p_email text,p_key text) returns jsonb
language plpgsql security definer set search_path='' as $$
declare l public.licenses; token text;
begin
  if p_email is null or p_key is null or length(p_email)>254 or length(p_key)<16 or length(p_key)>200 then raise exception 'access_denied'; end if;
  select * into l from public.licenses where email=lower(btrim(p_email))
    and key_hash=encode(extensions.digest(p_key,'sha256'),'hex') for update;
  if not found or not l.enabled or (l.expires_at is not null and l.expires_at<=now()) then raise exception 'access_denied'; end if;
  if l.session_hash is not null and l.lease_until>now() and l.session_expires_at>now() then raise exception 'session_in_use'; end if;
  token:=encode(extensions.gen_random_bytes(32),'hex');
  update public.licenses set session_hash=encode(extensions.digest(token,'sha256'),'hex'),
    active_session=gen_random_uuid()::text,lease_until=now()+interval '2 minutes',session_expires_at=now()+interval '8 hours' where id=l.id;
  return jsonb_build_object('token',token,'user_id',l.user_id);
end;
$$;

create or replace function private.require_license_session(p_token text,p_allow_renew boolean default false) returns public.licenses
language plpgsql security definer set search_path='' as $$
declare l public.licenses;
begin
  if p_token is null or length(p_token)<>64 then raise exception 'access_denied'; end if;
  select * into l from public.licenses where session_hash=encode(extensions.digest(p_token,'sha256'),'hex') for update;
  if not found or not l.enabled or (l.expires_at is not null and l.expires_at<=now())
    or l.session_expires_at<=now() or l.session_expires_at is null
    or (not p_allow_renew and (l.lease_until<=now() or l.lease_until is null)) then raise exception 'access_denied'; end if;
  return l;
end;
$$;
revoke all on function private.require_license_session(text,boolean) from public,anon,authenticated;

create or replace function public.license_heartbeat(p_token text) returns boolean
language plpgsql security definer set search_path='' as $$
declare l public.licenses;
begin
  l:=private.require_license_session(p_token,true);
  update public.licenses set lease_until=least(now()+interval '2 minutes',session_expires_at) where id=l.id;
  return true;
end;
$$;
create or replace function public.license_logout(p_token text) returns boolean
language plpgsql security definer set search_path='' as $$
begin
  if p_token is null or length(p_token)<>64 then raise exception 'access_denied'; end if;
  update public.licenses set session_hash=null,active_session=null,lease_until=null,session_expires_at=null
    where session_hash=encode(extensions.digest(p_token,'sha256'),'hex');
  return true;
end;
$$;
create or replace function public.license_records_list(p_token text,p_kind text,p_offset integer default 0,p_limit integer default 500)
returns setof public.records language plpgsql security definer set search_path='' as $$
declare l public.licenses;
begin
  l:=private.require_license_session(p_token);
  if p_offset<0 or p_limit<1 or p_limit>500 then raise exception 'invalid_pagination'; end if;
  return query select r.* from public.records r where r.user_id=l.user_id and r.kind=p_kind
    order by r.created_at,r.id offset p_offset limit p_limit;
end;
$$;
create or replace function public.license_record_put(p_token text,p_kind text,p_payload jsonb,p_id uuid) returns jsonb
language plpgsql security definer set search_path='' as $$
declare l public.licenses; saved public.records;
begin
  l:=private.require_license_session(p_token);
  if p_id is null or p_payload is null then raise exception 'invalid_record'; end if;
  insert into public.records(id,user_id,kind,payload) values(p_id,l.user_id,p_kind,p_payload)
    on conflict(id) do update set payload=excluded.payload
    where public.records.user_id=l.user_id and public.records.kind=p_kind returning * into saved;
  if not found then raise exception 'access_denied'; end if;
  return to_jsonb(saved);
end;
$$;
create or replace function public.license_reserve_ai(p_token text) returns boolean
language plpgsql security definer set search_path='' as $$
declare l public.licenses; today date:=(now() at time zone 'UTC')::date;
begin
  l:=private.require_license_session(p_token);
  insert into public.ai_usage(user_id,day,calls) values(l.user_id,today,0) on conflict do nothing;
  update public.ai_usage set calls=calls+1 where user_id=l.user_id and day=today and calls<l.daily_ai_limit;
  if not found then raise exception 'daily_ai_limit'; end if;
  return true;
end;
$$;
revoke all on function public.license_login(text,text),public.license_heartbeat(text),public.license_logout(text),public.license_records_list(text,text,integer,integer),public.license_record_put(text,text,jsonb,uuid),public.license_reserve_ai(text) from public,authenticated;
grant execute on function public.license_login(text,text),public.license_heartbeat(text),public.license_logout(text),public.license_records_list(text,text,integer,integer),public.license_record_put(text,text,jsonb,uuid),public.license_reserve_ai(text) to anon;

commit;
