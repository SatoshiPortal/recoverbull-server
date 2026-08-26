// @generated automatically by Diesel CLI.
//! Diesel schema generated from migrations; keep this file synchronized with
//! the migration source and do not add domain behavior here.

diesel::table! {
    secret (id) {
        id -> Text,
        created_at -> Text,
        encrypted_secret -> Text,
    }
}
