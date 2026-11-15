-- Manual crypto payout flow: the admin sends the transfer first, then approves
-- it here. Reserve the client's balance at request time; rejection restores it.
create or replace function public.create_crypto_withdrawal(
  _user_id uuid,
  _amount_ksh numeric,
  _amount_usd numeric,
  _destination_address text
)
returns public.transactions
language plpgsql
security definer
set search_path = public
as $$
declare
  _profile public.profiles;
  _tx public.transactions;
begin
  if current_setting('role', true) is distinct from 'service_role' then
    raise exception 'Unauthorized';
  end if;

  select * into _profile
  from public.profiles
  where id = _user_id
  for update;

  if _profile.id is null then raise exception 'Profile not found'; end if;
  if coalesce(_profile.balance_usd, 0) < _amount_usd then raise exception 'Insufficient balance'; end if;

  update public.profiles
  set balance_usd = coalesce(balance_usd, 0) - _amount_usd,
      updated_at = now()
  where id = _user_id;

  insert into public.transactions (
    user_id, kind, method, account_type, amount, currency, amount_usd,
    status, is_virtual, meta
  ) values (
    _user_id, 'withdraw', 'crypto', 'real', _amount_ksh, 'KSH', _amount_usd,
    'pending', false,
    jsonb_build_object(
      'crypto_destination_address', _destination_address,
      'crypto_withdrawal_state', 'awaiting_admin_review',
      'admin_approval_required', true,
      'balance_deducted', true,
      'balance_reserved_at', now(),
      'submitted_at', now()
    )
  ) returning * into _tx;

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
  if current_setting('role', true) is distinct from 'service_role' then
    raise exception 'Unauthorized';
  end if;

  select * into _tx
  from public.transactions
  where id = _transaction_id
  for update;

  if _tx.id is null or _tx.kind <> 'withdraw' or _tx.method <> 'crypto'
     or _tx.status <> 'pending' then
    raise exception 'Crypto withdrawal is no longer awaiting review';
  end if;

  if coalesce((_tx.meta->>'balance_deducted')::boolean, false) is true then
    update public.profiles
    set balance_usd = coalesce(balance_usd, 0) + coalesce(_tx.amount_usd, 0),
        updated_at = now()
    where id = _tx.user_id;
  end if;

  update public.transactions
  set status = 'cancelled',
      meta = coalesce(meta, '{}'::jsonb) || jsonb_build_object(
        'crypto_withdrawal_state', 'rejected',
        'balance_deducted', false,
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

-- Debit on approval for legacy pending requests; new requests are already
-- reserved, so completion only records that the external transfer was sent.
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
  _profile public.profiles;
begin
  if current_setting('role', true) is distinct from 'service_role' then
    raise exception 'Unauthorized';
  end if;

  select * into _tx
  from public.transactions
  where id = _transaction_id
  for update;

  if _tx.id is null or _tx.kind <> 'withdraw' or _tx.method <> 'crypto'
     or _tx.account_type <> 'real' then
    raise exception 'Crypto withdrawal not found';
  end if;

  if _tx.status = 'pending' then
    if coalesce((_tx.meta->>'balance_deducted')::boolean, false) is not true then
      select * into _profile
      from public.profiles
      where id = _tx.user_id
      for update;

      if _profile.id is null then raise exception 'Profile not found'; end if;
      if coalesce(_profile.balance_usd, 0) < coalesce(_tx.amount_usd, 0) then
        raise exception 'Insufficient balance to approve crypto withdrawal';
      end if;

      update public.profiles
      set balance_usd = coalesce(balance_usd, 0) - coalesce(_tx.amount_usd, 0),
          updated_at = now()
      where id = _tx.user_id;
    end if;
  elsif _tx.status = 'processing'
        and coalesce((_tx.meta->>'balance_deducted')::boolean, false) is true then
    -- Support requests approved under the previous two-step flow.
    null;
  else
    raise exception 'Crypto withdrawal is no longer awaiting payment approval';
  end if;

  update public.transactions
  set status = 'completed',
      meta = coalesce(meta, '{}'::jsonb) || jsonb_build_object(
        'crypto_withdrawal_state', 'sent',
        'balance_deducted', true,
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

revoke all on function public.complete_crypto_withdrawal(uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.create_crypto_withdrawal(uuid, numeric, numeric, text) from public, anon, authenticated;
revoke all on function public.reject_crypto_withdrawal(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.complete_crypto_withdrawal(uuid, uuid, text) to service_role;
grant execute on function public.create_crypto_withdrawal(uuid, numeric, numeric, text) to service_role;
grant execute on function public.reject_crypto_withdrawal(uuid, uuid, text) to service_role;

notify pgrst, 'reload schema';
