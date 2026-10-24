-- The tables the device endpoints read and write, as the PHP console's migrations (v1.15.0-hte.1) create them
-- through Laravel's SQLite grammar (string -> varchar, boolean -> tinyint(1), timestamp -> datetime, json -> text,
-- every integer kind -> integer). Hand-written for the tests: no PHP on the build machine. Column types matter,
-- they decide SQLite's affinity and so what is stored; columns no phase 1 code touches are kept where cheap.
-- The replay (replay/replay.sh) runs against a database PHP itself migrated, which is the real check.

create table "users" ("id" integer primary key autoincrement not null, "username" varchar not null, "name" varchar, "email" varchar, "password" varchar not null, "avatar" varchar, "user_group_id" integer, "is_admin" tinyint(1) not null default '0', "is_active" tinyint(1) not null default '1', "note" varchar, "totp_secret" varchar, "remember_token" varchar, "created_at" datetime, "updated_at" datetime);
create unique index "users_username_unique" on "users" ("username");

create table "device_groups" ("id" integer primary key autoincrement not null, "name" varchar not null, "note" varchar, "created_at" datetime, "updated_at" datetime);

create table "devices" ("id" integer primary key autoincrement not null, "rustdesk_id" varchar not null, "uuid" varchar not null, "status" varchar not null default 'active', "can_initiate" tinyint(1) not null default '1', "hostname" varchar, "os" varchar, "cpu" varchar, "memory" varchar, "username" varchar, "version" varchar, "alias" varchar, "note" varchar, "user_id" integer, "device_group_id" integer, "strategy_id_resolved" integer, "strategy_version" integer, "strategy_options" text, "strategy_acked_options" text, "strategy_acked_at" datetime, "strategy_sent_at" datetime, "last_online_at" datetime, "last_online_ip" varchar, "registered_ip" varchar, "lan_ip" varchar, "lan_ip_seen_at" datetime, "deleted_at" datetime, "created_at" datetime, "updated_at" datetime);
create unique index "devices_rustdesk_id_unique" on "devices" ("rustdesk_id");
create index "devices_uuid_index" on "devices" ("uuid");

create table "client_tokens" ("id" integer primary key autoincrement not null, "user_id" integer not null, "token" varchar not null, "device_id" varchar, "device_uuid" varchar, "device_os" varchar, "device_name" varchar, "client_type" varchar, "expires_at" datetime, "last_used_at" datetime, "created_at" datetime, "updated_at" datetime);

create table "audit_connections" ("id" integer primary key autoincrement not null, "action" varchar, "conn_id" integer not null default '0', "rustdesk_id" varchar not null, "from_peer" varchar, "from_name" varchar, "ip" varchar, "session_id" varchar, "conn_type" integer not null default '0', "uuid" varchar, "guid" varchar, "note" text, "note_user_id" integer, "noted_at" datetime, "closed_at" datetime, "disconnect_requested_at" datetime, "disconnect_sent_at" datetime, "disconnect_requested_by" integer, "created_at" datetime, "updated_at" datetime, foreign key("disconnect_requested_by") references "users"("id") on delete set null, foreign key("note_user_id") references "users"("id") on delete set null);
create index "audit_connections_conn_id_index" on "audit_connections" ("conn_id");
create index "audit_connections_rustdesk_id_index" on "audit_connections" ("rustdesk_id");
create unique index "audit_connections_guid_unique" on "audit_connections" ("guid");

create table "audit_file_transfers" ("id" integer primary key autoincrement not null, "rustdesk_id" varchar not null, "from_peer" varchar, "from_name" varchar, "path" text, "info" text, "is_file" tinyint(1) not null default '1', "direction" integer not null default '0', "file_count" integer not null default '0', "ip" varchar, "uuid" varchar, "created_at" datetime, "updated_at" datetime);

create table "alarm_logs" ("id" integer primary key autoincrement not null, "rustdesk_id" varchar not null, "uuid" varchar, "typ" integer not null default '0', "info" text, "conn_id" integer, "created_at" datetime, "updated_at" datetime);

create table "settings" ("key" varchar not null, "value" text, "created_at" datetime, "updated_at" datetime, primary key ("key"));

create table "strategies" ("id" integer primary key autoincrement not null, "name" varchar not null, "note" varchar, "enabled" tinyint(1) not null default '1', "is_default" tinyint(1) not null default '0', "enforce" tinyint(1) not null default '0', "confirmation_timeout_minutes" integer not null default '15', "options" text, "active_revision_id" integer, "created_at" datetime, "updated_at" datetime, "deleted_at" datetime);
create table "device_strategy" ("device_id" integer not null, "strategy_id" integer not null, foreign key("device_id") references "devices"("id") on delete cascade, foreign key("strategy_id") references "strategies"("id") on delete cascade);
create table "strategy_user" ("user_id" integer not null, "strategy_id" integer not null, foreign key("user_id") references "users"("id") on delete cascade, foreign key("strategy_id") references "strategies"("id") on delete cascade);
create table "device_group_strategy" ("device_group_id" integer not null, "strategy_id" integer not null, foreign key("device_group_id") references "device_groups"("id") on delete cascade, foreign key("strategy_id") references "strategies"("id") on delete cascade);

create table "device_presence_notification_states" ("id" integer primary key autoincrement not null, "device_id" integer not null, "offline_notified_at" datetime, "created_at" datetime, "updated_at" datetime, foreign key("device_id") references "devices"("id") on delete cascade);

create table "address_book_entries" ("id" integer primary key autoincrement not null, "address_book_id" integer not null, "rustdesk_id" varchar not null, "alias" varchar, "hostname" varchar, "platform" varchar, "username" varchar, "password_enc" text, "hash" varchar, "login_name" varchar, "force_always_relay" tinyint(1) not null default '0', "rdp_port" varchar, "rdp_username" varchar, "tag_ids" text, "created_at" datetime, "updated_at" datetime);

create table "hte_device_passwords" ("id" integer primary key autoincrement not null, "rustdesk_id" varchar not null, "capable_at" datetime, "current_version" integer not null default '0', "current_enc" text, "issued_at" datetime, "issued_reason" varchar, "confirmed_version" integer not null default '0', "confirmed_enc" text, "confirmed_at" datetime, "reach_user_ids" text, "created_at" datetime, "updated_at" datetime);
create unique index "hte_device_passwords_rustdesk_id_unique" on "hte_device_passwords" ("rustdesk_id");
create table "hte_auto_books" ("id" integer primary key autoincrement not null, "user_id" integer not null, "address_book_id" integer not null, "created_at" datetime, "updated_at" datetime);
