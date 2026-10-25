-- Phase 5: the further tables the admin automation API reads and writes, as the PHP console's migrations
-- (v1.15.0-hte.1) create them on SQLite. Applied after schema.sql and schema_p4.sql.
create table "api_tokens" ("id" integer primary key autoincrement not null, "name" varchar not null, "token_hash" varchar not null, "token_prefix" varchar not null, "user_id" integer, "permissions" text not null, "last_used_at" datetime, "expires_at" datetime, "is_active" tinyint(1) not null default '1', "created_at" datetime, "updated_at" datetime, foreign key("user_id") references "users"("id") on delete set null);
create unique index "api_tokens_token_hash_unique" on "api_tokens" ("token_hash");
create index "api_tokens_is_active_index" on "api_tokens" ("is_active");
create table "sessions" ("id" varchar not null, "user_id" integer, "ip_address" varchar, "user_agent" text, "payload" text not null, "last_activity" integer not null, primary key ("id"));
create index "sessions_user_id_index" on "sessions" ("user_id");
create table "trusted_devices" ("id" integer primary key autoincrement not null, "user_id" integer not null, "token_hash" varchar not null, "label" varchar, "ip" varchar, "last_used_at" datetime, "expires_at" datetime not null default CURRENT_TIMESTAMP, "created_at" datetime, "updated_at" datetime, foreign key("user_id") references "users"("id") on delete cascade);
create unique index "trusted_devices_token_hash_unique" on "trusted_devices" ("token_hash");
create table "console_audits" ("id" integer primary key autoincrement not null, "user_id" integer, "username" varchar, "action" varchar not null, "target_type" varchar, "target_id" varchar, "summary" varchar not null, "ip" varchar, "created_at" datetime, foreign key("user_id") references "users"("id") on delete set null);
create index "console_audits_action_index" on "console_audits" ("action");
create table "device_duplicate_dismissals" ("id" integer primary key autoincrement not null, "device_id" integer not null, "other_device_id" integer not null, "user_id" integer, "created_at" datetime, "updated_at" datetime, foreign key("device_id") references "devices"("id") on delete cascade, foreign key("other_device_id") references "devices"("id") on delete cascade, foreign key("user_id") references "users"("id") on delete set null);
create unique index "device_duplicate_dismissals_device_id_other_device_id_unique" on "device_duplicate_dismissals" ("device_id", "other_device_id");
