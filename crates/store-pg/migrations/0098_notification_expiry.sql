-- Account links that expired before mail transport accepted them are terminal.
alter table outbox drop constraint outbox_status_check;
alter table outbox add constraint outbox_status_check
    check (status in ('pending', 'claimed', 'delivered', 'failed', 'abandoned', 'expired'));

alter table outbox_attempts drop constraint outbox_attempts_outcome_check;
alter table outbox_attempts add constraint outbox_attempts_outcome_check
    check (outcome in ('delivered', 'journalled', 'retry', 'abandoned', 'expired'));
