ALTER TABLE cases ADD COLUMN collection_case_id TEXT;

UPDATE cases
SET collection_case_id = case_id
WHERE collection_case_id IS NULL OR collection_case_id = '';
