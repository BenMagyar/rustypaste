ALTER TABLE pastes ADD COLUMN link_key TEXT;

CREATE UNIQUE INDEX pastes_public_link_key
    ON pastes (link_key)
    WHERE link_key IS NOT NULL;
