// @generated automatically by Diesel CLI.

diesel::table! {
    secret (id) {
        id -> Text,
        created_at -> Text,
        encrypted_secret -> Text,
    }
}
