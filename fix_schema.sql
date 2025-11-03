-- Normalize schema by creating views with consistent names

-- Drop old views if they exist
DROP VIEW IF EXISTS v_blocks;
DROP VIEW IF EXISTS v_transactions;
DROP VIEW IF EXISTS v_tx_in;
DROP VIEW IF EXISTS v_tx_out;

-- Map blocks table
CREATE VIEW v_blocks AS
SELECT
    height AS height,
    hash   AS hash,
    time   AS time,
    version AS version,
    merkle_root AS merkle_root,
    nonce AS nonce,
    bits  AS bits
FROM blocks;

-- Map transactions table (auto-detect real column names)
CREATE VIEW v_transactions AS
SELECT
    COALESCE(txid, tx_hash) AS txid,
    COALESCE(block_height, blk_height, block) AS block_height,
    version,
    lock_time
FROM transactions;

-- Map tx_in table
CREATE VIEW v_tx_in AS
SELECT
    COALESCE(txid, tx_hash) AS txid,
    COALESCE(input_index, vin, idx) AS input_index,
    COALESCE(prev_txid, prev_hash) AS prev_txid,
    COALESCE(prev_vout, vout) AS prev_vout,
    COALESCE(scriptSig, script) AS scriptSig,
    sequence
FROM tx_in;

-- Map tx_out table
CREATE VIEW v_tx_out AS
SELECT
    COALESCE(txid, tx_hash) AS txid,
    COALESCE(vout, n, idx) AS vout,
    value,
    scriptPubKey,
    address
FROM tx_out;
