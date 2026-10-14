-- ==============================================================================
-- OneVault (share-shield) Database Roles & Least-Privilege Access Control
-- ==============================================================================

-- 1. Schema Owner / Migration Role
-- Used exclusively during deployment to run versioned DDL migrations.
-- NEVER used by the runtime application process.
CREATE ROLE onevault_owner WITH
  LOGIN
  PASSWORD 'REPLACE_WITH_STRONG_OWNER_PASSWORD'
  NOSUPERUSER
  INHERIT
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

-- 2. Runtime Application Role
-- Used by the Express API service at runtime.
-- Strictly limited to DML (SELECT, INSERT, UPDATE, DELETE) on data tables.
-- DDL operations (CREATE, ALTER, DROP, TRUNCATE) are forbidden.
CREATE ROLE onevault_runtime WITH
  LOGIN
  PASSWORD 'REPLACE_WITH_STRONG_RUNTIME_PASSWORD'
  NOSUPERUSER
  INHERIT
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

-- 3. Database Ownership
ALTER DATABASE onevault_dev OWNER TO onevault_owner;

-- 4. Schema Permissions
\connect onevault_dev

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO onevault_runtime;
GRANT ALL ON SCHEMA public TO onevault_owner;

-- 5. Table Permissions
-- Grant least-privilege DML only to the runtime role on the secrets table
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.secrets TO onevault_runtime;

-- Ensure future tables created by owner grant runtime DML permissions
ALTER DEFAULT PRIVILEGES FOR ROLE onevault_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO onevault_runtime;

-- Verify: onevault_runtime cannot drop, truncate, or alter tables
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM onevault_runtime;
