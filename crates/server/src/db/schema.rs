// @generated automatically by Diesel CLI.

diesel::table! {
    acte_participants (acte_uuid, participant_sn) {
        acte_uuid -> Text,
        participant_sn -> Text,
        c_acte_key -> Text,
        added_at -> BigInt,
        added_by_sn -> Text,
        history_from -> Nullable<BigInt>,
    }
}

diesel::table! {
    actes (uuid) {
        uuid -> Text,
        titre -> Text,
        notaire_sn -> Text,
        created_at -> BigInt,
        closed_at -> Nullable<BigInt>,
        c_acte_archive -> Text,
    }
}

diesel::table! {
    identities (sn) {
        sn -> Text,
        si -> Text,
        pk -> Text,
        tbs_cert -> Text,
        lra_id -> Text,
        registered_at -> BigInt,
        revoked_at -> Nullable<BigInt>,
    }
}

diesel::table! {
    merkle_log (id) {
        id -> BigInt,
        acte_uuid -> Text,
        message_id -> Text,
        leaf_hash -> Text,
        parent_hash -> Nullable<Text>,
        en_signature -> Nullable<Text>,
        logged_at -> BigInt,
    }
}

diesel::table! {
    messages (id) {
        id -> Text,
        acte_uuid -> Text,
        sender_sn -> Text,
        c_message -> Text,
        nonce -> Text,
        signature -> Text,
        seq -> BigInt,
        sent_at -> BigInt,
    }
}

diesel::table! {
    sessions (token) {
        token -> Text,
        sn -> Text,
        created_at -> BigInt,
        expires_at -> BigInt,
    }
}

diesel::joinable!(acte_participants -> actes (acte_uuid));
diesel::joinable!(acte_participants -> identities (participant_sn));
diesel::joinable!(actes -> identities (notaire_sn));
diesel::joinable!(merkle_log -> actes (acte_uuid));
diesel::joinable!(merkle_log -> messages (message_id));
diesel::joinable!(messages -> actes (acte_uuid));
diesel::joinable!(messages -> identities (sender_sn));
diesel::joinable!(sessions -> identities (sn));

diesel::allow_tables_to_appear_in_same_query!(
    acte_participants,
    actes,
    identities,
    merkle_log,
    messages,
    sessions,
);
