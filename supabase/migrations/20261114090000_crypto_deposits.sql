alter table public.system_settings
  add column if not exists crypto_deposit_address text not null default '',
  add column if not exists crypto_deposit_instructions text not null default '';

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'crypto-deposit-receipts',
  'crypto-deposit-receipts',
  false,
  8388608,
  array['image/jpeg', 'image/png', 'image/webp']::text[]
)
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Users upload own crypto deposit receipts" on storage.objects;
create policy "Users upload own crypto deposit receipts"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'crypto-deposit-receipts'
  and (storage.foldername(name))[1] = auth.uid()::text
  and (storage.foldername(name))[2] ~* '^[0-9a-f-]{36}$'
);

drop policy if exists "Users read own crypto deposit receipts" on storage.objects;
create policy "Users read own crypto deposit receipts"
on storage.objects for select to authenticated
using (
  bucket_id = 'crypto-deposit-receipts'
  and (storage.foldername(name))[1] = auth.uid()::text
);

notify pgrst, 'reload schema';

create or replace function public.approve_crypto_withdrawal(
  _transaction_id uuid,
  _admin_id uuid
)
returns public.transactions
language plpgsql
security definer
set search_path = public
as $$
declare
  _tx public.transactions;
  _profile public.profiles;
begin
  if current_setting('role', true) is distinct from 'service_role' then
    raise exception 'Unauthorized';
  end if;

  select * into _tx from public.transactions where id = _transaction_id for update;
  if _tx.id is null or _tx.kind <> 'withdraw' or _tx.method <> 'crypto'
     or _tx.account_type <> 'real' or _tx.status <> 'pending' then
    raise exception 'Crypto withdrawal is no longer awaiting approval';
  end if;

  select * into _profile from public.profiles where id = _tx.user_id for update;
  if _profile.id is null then raise exception 'Profile not found'; end if;
  if _profile.balance_usd < _tx.amount_usd then raise exception 'Insufficient balance'; end if;

  update public.profiles
  set balance_usd = balance_usd - _tx.amount_usd, updated_at = now()
  where id = _tx.user_id;

  update public.transactions
  set status = 'processing',
      meta = meta || jsonb_build_object(
        'crypto_withdrawal_state', 'approved_awaiting_transfer',
        'balance_deducted', true,
        'approved_by', _admin_id,
        'approved_at', now()
      ),
      updated_at = now()
  where id = _transaction_id
  returning * into _tx;
  return _tx;
end;
$$;

create or replace function public.reject_crypto_withdrawal(
  _transaction_id uuid,
  _admin_id uuid,
  _reason text default null
)
returns public.transactions
language plpgsql
security definer
set search_path = public
as $$
declare
  _tx public.transactions;
begin
  if current_setting('role', true) <> 'service_role' then
    raise exception 'Unauthorized';
  end if;

  select * into _tx from public.transactions where id = _transaction_id for update;
  if _tx.id is null or _tx.kind <> 'withdraw' or _tx.method <> 'crypto'
     or _tx.status <> 'pending' then
    raise exception 'Crypto withdrawal is no longer awaiting review';
  end if;

  update public.transactions
  set status = 'cancelled',
      meta = meta || jsonb_build_object(
        'crypto_withdrawal_state', 'rejected',
        'rejected_by', _admin_id,
        'rejected_at', now(),
        'rejection_reason', _reason
      ),
      updated_at = now()
  where id = _transaction_id
  returning * into _tx;
  return _tx;
end;
$$;

create or replace function public.complete_crypto_withdrawal(
  _transaction_id uuid,
  _admin_id uuid,
  _transaction_hash text default null
)
returns public.transactions
language plpgsql
security definer
set search_path = public
as $$
declare
  _tx public.transactions;
begin
  if current_setting('role', true) <> 'service_role' then
    raise exception 'Unauthorized';
  end if;

  select * into _tx from public.transactions where id = _transaction_id for update;
  if _tx.id is null or _tx.kind <> 'withdraw' or _tx.method <> 'crypto'
     or _tx.status <> 'processing' or coalesce((_tx.meta->>'balance_deducted')::boolean, false) is not true then
    raise exception 'Crypto withdrawal is not awaiting transfer confirmation';
  end if;

  update public.transactions
  set status = 'completed',
      meta = meta || jsonb_build_object(
        'crypto_withdrawal_state', 'sent',
        'transaction_hash', nullif(_transaction_hash, ''),
        'sent_by', _admin_id,
        'sent_at', now()
      ),
      updated_at = now()
  where id = _transaction_id
  returning * into _tx;
  return _tx;
end;
$$;

revoke all on function public.approve_crypto_withdrawal(uuid, uuid) from public, anon, authenticated;
revoke all on function public.reject_crypto_withdrawal(uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.complete_crypto_withdrawal(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.approve_crypto_withdrawal(uuid, uuid) to service_role;
grant execute on function public.reject_crypto_withdrawal(uuid, uuid, text) to service_role;
grant execute on function public.complete_crypto_withdrawal(uuid, uuid, text) to service_role;

notify pgrst, 'reload schema';
