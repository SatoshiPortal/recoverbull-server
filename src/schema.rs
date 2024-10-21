// @generated automatically by Diesel CLI.

diesel::table! {
    key (id) {
        id -> Text,
        created_at -> Text,
        secret -> Text,
        private -> Text,
        requested_at -> Nullable<Text>,
    }
}
