// @generated automatically by Diesel CLI.

diesel::table! {
    key (id) {
        id -> Text,
        created_at -> Text,
        secret -> Text,
        backup_key -> Text,
        requested_at -> Nullable<Text>,
    }
}
