-- AI ScamShield Database Migration
-- Execute this script in the Supabase SQL Editor (https://supabase.com/dashboard/project/tfosknniuzdtxhcnanpy/sql)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Threat Level and Category Enums
DO $$ BEGIN
    CREATE TYPE threat_level_enum AS ENUM ('SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE input_type_enum AS ENUM ('TEXT', 'EMAIL', 'URL', 'IMAGE');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scam_category_enum AS ENUM (
        'PHISHING_CREDENTIAL_THEFT',
        'BANKING_FINANCIAL_IMPERSONATION',
        'FAKE_JOB_TASK_FRAUD',
        'CRYPTO_INVESTMENT_SCAM',
        'TECH_SUPPORT_EXTORTION',
        'PACKAGE_DELIVERY_SCAM',
        'GOVERNMENT_LEGAL_IMPERSONATION',
        'LOTTERY_PRIZE_SCAM',
        'ROMANCE_ADVANCE_FEE',
        'MALICIOUS_SOFTWARE_URL',
        'LEGITIMATE_COMMUNICATION'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 1. PROFILES TABLE
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    reputation_score INT DEFAULT 10 CHECK (reputation_score >= 0),
    is_analyst BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- 2. SCAM ANALYSES TABLE
CREATE TABLE IF NOT EXISTS public.scam_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    session_id TEXT NOT NULL,
    input_type input_type_enum NOT NULL,
    raw_input_snippet TEXT NOT NULL,
    sanitized_input TEXT NOT NULL,
    input_metadata JSONB DEFAULT '{}'::jsonb,
    risk_score INT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level threat_level_enum NOT NULL,
    primary_category scam_category_enum NOT NULL,
    confidence_score NUMERIC(4,3) NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 1.0),
    summary TEXT NOT NULL,
    psychological_triggers TEXT[] DEFAULT '{}',
    is_safe_to_engage BOOLEAN NOT NULL,
    language_code VARCHAR(10) DEFAULT 'en',
    client_ip_hash VARCHAR(64) NOT NULL,
    is_public_feed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- 3. SCAM INDICATORS TABLE
CREATE TABLE IF NOT EXISTS public.scam_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID NOT NULL REFERENCES public.scam_analyses(id) ON DELETE CASCADE,
    indicator_type VARCHAR(50) NOT NULL,
    severity threat_level_enum NOT NULL,
    title VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    evidence_snippet TEXT,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- 4. RECOMMENDED ACTIONS TABLE
CREATE TABLE IF NOT EXISTS public.recommended_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID NOT NULL REFERENCES public.scam_analyses(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    urgency VARCHAR(20) NOT NULL CHECK (urgency IN ('IMMEDIATE', 'SECONDARY', 'PREVENTATIVE')),
    action_text TEXT NOT NULL,
    official_link TEXT,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- 5. THREAT INTELLIGENCE FEED TABLE
CREATE TABLE IF NOT EXISTS public.threat_feed (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES public.scam_analyses(id) ON DELETE SET NULL,
    title VARCHAR(200) NOT NULL,
    scam_category scam_category_enum NOT NULL,
    risk_level threat_level_enum NOT NULL,
    redacted_sample TEXT NOT NULL,
    upvotes INT DEFAULT 0,
    false_positive_reports INT DEFAULT 0,
    is_verified_by_analyst BOOLEAN DEFAULT FALSE,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- 6. COMMUNITY VOTES TABLE
CREATE TABLE IF NOT EXISTS public.community_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id UUID NOT NULL REFERENCES public.threat_feed(id) ON DELETE CASCADE,
    voter_identifier VARCHAR(64) NOT NULL,
    vote_type VARCHAR(20) NOT NULL CHECK (vote_type IN ('UPVOTE', 'FALSE_POSITIVE')),
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL,
    CONSTRAINT unique_vote_per_identity UNIQUE(feed_id, voter_identifier, vote_type)
);

-- 7. URL REPUTATION CACHE TABLE
CREATE TABLE IF NOT EXISTS public.url_reputation_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    full_url_hash VARCHAR(64) NOT NULL,
    domain_age_days INT,
    registrar TEXT,
    is_blacklisted BOOLEAN DEFAULT FALSE,
    dns_records JSONB DEFAULT '{}'::jsonb,
    whois_raw JSONB DEFAULT '{}'::jsonb,
    threat_verdict JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scam_analyses_user ON public.scam_analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_scam_analyses_created ON public.scam_analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scam_analyses_risk_level ON public.scam_analyses(risk_level);
CREATE INDEX IF NOT EXISTS idx_threat_feed_category ON public.threat_feed(scam_category);
CREATE INDEX IF NOT EXISTS idx_threat_feed_created ON public.threat_feed(created_at DESC);

-- Enable Row Level Security
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scam_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scam_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recommended_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_feed ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.community_votes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.url_reputation_cache ENABLE ROW LEVEL SECURITY;

-- Policies for public reading and service role
CREATE POLICY "Public read scam analyses" ON public.scam_analyses FOR SELECT USING (true);
CREATE POLICY "Service and user insert scam analyses" ON public.scam_analyses FOR INSERT WITH CHECK (true);

CREATE POLICY "Public read indicators" ON public.scam_indicators FOR SELECT USING (true);
CREATE POLICY "Public read actions" ON public.recommended_actions FOR SELECT USING (true);

CREATE POLICY "Public read threat feed" ON public.threat_feed FOR SELECT USING (true);
CREATE POLICY "Insert threat feed" ON public.threat_feed FOR INSERT WITH CHECK (true);
CREATE POLICY "Update threat feed votes" ON public.threat_feed FOR UPDATE USING (true);

CREATE POLICY "Public read community votes" ON public.community_votes FOR SELECT USING (true);
CREATE POLICY "Insert community votes" ON public.community_votes FOR INSERT WITH CHECK (true);
