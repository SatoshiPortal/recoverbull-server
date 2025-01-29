// @generated automatically by Diesel CLI.

diesel::table! {
    key (id) {
        id -> Text,
        created_at -> Text,
        encrypted_backup_key -> Text,
    }
}

diesel::table! {
    secret (id) {
        id -> Text,
        created_at -> Text,
        encrypted_secret -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    key,
    secret,
);
