-- IPG account ownership and tournament joining
-- Run this migration in Supabase SQL Editor.

ALTER TABLE public.clubs
ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS clubs_owner_id_unique
ON public.clubs(owner_id)
WHERE owner_id IS NOT NULL;

-- Allow verified users to claim an existing club only when the auth email
-- exactly matches the club's registered contact email.
CREATE OR REPLACE FUNCTION public.claim_existing_club()
RETURNS SETOF public.clubs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  user_email TEXT;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'You must be signed in';
  END IF;

  user_email := lower(coalesce(auth.jwt() ->> 'email', ''));

  RETURN QUERY
  UPDATE public.clubs c
  SET owner_id = auth.uid()
  WHERE lower(c.contact_email) = user_email
    AND c.owner_id IS NULL
  RETURNING c.*;

  IF NOT FOUND THEN
    RETURN QUERY
    SELECT c.*
    FROM public.clubs c
    WHERE c.owner_id = auth.uid()
    LIMIT 1;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.claim_existing_club() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.claim_existing_club() TO authenticated;

-- Remove the old anonymous registration path; new registrations require
-- a verified account and an owner_id.
DROP POLICY IF EXISTS "Anyone can submit club registration" ON public.clubs;
DROP POLICY IF EXISTS "Public can register clubs" ON public.clubs;
DROP POLICY IF EXISTS "Users can register their own club" ON public.clubs;

CREATE POLICY "Users can register their own club"
ON public.clubs FOR INSERT TO authenticated
WITH CHECK (
  owner_id = auth.uid()
  AND status = 'pending'
  AND lower(contact_email) = lower(coalesce(auth.jwt() ->> 'email', ''))
);

CREATE POLICY "Club owners can read their club"
ON public.clubs FOR SELECT TO authenticated
USING (owner_id = auth.uid() OR public.is_ipg_admin());

CREATE TABLE IF NOT EXISTS public.tournament_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tournament_id UUID NOT NULL REFERENCES public.tournaments(id) ON DELETE CASCADE,
  club_id UUID NOT NULL REFERENCES public.clubs(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'joined' CHECK (status IN ('joined','withdrawn')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_club_tournament UNIQUE (tournament_id, club_id)
);

ALTER TABLE public.tournament_entries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Clubs can read their own entries" ON public.tournament_entries;
CREATE POLICY "Clubs can read their own entries"
ON public.tournament_entries FOR SELECT TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.clubs c
    WHERE c.id = tournament_entries.club_id AND c.owner_id = auth.uid()
  )
  OR public.is_ipg_admin()
);

DROP POLICY IF EXISTS "Approved clubs can join open tournaments" ON public.tournament_entries;
CREATE POLICY "Approved clubs can join open tournaments"
ON public.tournament_entries FOR INSERT TO authenticated
WITH CHECK (
  status = 'joined'
  AND EXISTS (
    SELECT 1 FROM public.clubs c
    WHERE c.id = tournament_entries.club_id
      AND c.owner_id = auth.uid()
      AND c.status = 'approved'
  )
  AND EXISTS (
    SELECT 1 FROM public.tournaments t
    WHERE t.id = tournament_entries.tournament_id
      AND t.status = 'registration_open'
      AND (t.registration_deadline IS NULL OR t.registration_deadline > NOW())
  )
);
