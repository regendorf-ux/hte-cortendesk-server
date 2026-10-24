-- Phase 4: the further tables the bearer-token client endpoints read and write, as the PHP console's migrations
-- (v1.15.0-hte.1) create them. Applied after schema.sql (address_book_entries and hte_auto_books are there).
create table "address_books" ("id" integer primary key autoincrement not null, "guid" varchar not null, "name" varchar not null, "owner_user_id" integer not null, "is_personal" tinyint(1) not null default '0', "note" varchar, "created_at" datetime, "updated_at" datetime);
create unique index "address_books_guid_unique" on "address_books" ("guid");
create index "address_books_owner_user_id_index" on "address_books" ("owner_user_id");
create table "address_book_rules" ("id" integer primary key autoincrement not null, "address_book_id" integer not null, "subject_type" varchar not null, "subject_id" integer, "permission" integer not null, "created_at" datetime, "updated_at" datetime);
create index "address_book_rules_address_book_id_index" on "address_book_rules" ("address_book_id");
create table "tags" ("id" integer primary key autoincrement not null, "address_book_id" integer not null, "name" varchar not null, "color" integer not null default '0', "created_at" datetime, "updated_at" datetime);
create index "tags_address_book_id_index" on "tags" ("address_book_id");
create unique index "tags_address_book_id_name_unique" on "tags" ("address_book_id", "name");
create table "device_group_user" ("user_id" integer not null, "device_group_id" integer not null, foreign key("user_id") references "users"("id") on delete cascade, foreign key("device_group_id") references "device_groups"("id") on delete cascade, primary key ("user_id", "device_group_id"));
create table "device_group_user_group" ("device_group_id" integer not null, "user_group_id" integer not null, foreign key("device_group_id") references "device_groups"("id") on delete cascade, foreign key("user_group_id") references "user_groups"("id") on delete cascade, primary key ("device_group_id", "user_group_id"));
create table "group_accesses" ("id" integer primary key autoincrement not null, "accessor_type" varchar not null, "accessor_id" integer not null, "target_type" varchar not null, "target_id" integer not null, "created_at" datetime, "updated_at" datetime);
create unique index "group_accesses_unique" on "group_accesses" ("accessor_type", "accessor_id", "target_type", "target_id");
create index "group_accesses_target_type_target_id_index" on "group_accesses" ("target_type", "target_id");
create index "group_accesses_accessor_type_accessor_id_index" on "group_accesses" ("accessor_type", "accessor_id");
create unique index "address_book_entries_address_book_id_rustdesk_id_unique" on "address_book_entries" ("address_book_id", "rustdesk_id");
