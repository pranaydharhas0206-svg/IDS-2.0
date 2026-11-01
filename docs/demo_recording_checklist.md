# Demo Video Recording Checklist

This is a human task — screen recording can't be done by an agent. Target:
a single 60-90 second screen capture showing the toolkit working end to end,
for judges who won't run the code themselves.

## Before recording

- [ ] `pip install -e ".[web]"` in a clean-ish terminal (or at least a clean
      `cases/` directory) so the case list starts empty/uncluttered.
- [ ] `python -m toolkit.web` running, browser open to `http://127.0.0.1:8000`.
- [ ] Have `sample_data/ardupilot_sample.bin` ready to select in the upload
      dialog.
- [ ] Decide narration approach: live voiceover, or silent with on-screen
      captions added in post. Either is fine — the point is judges can
      follow what's happening without reading code.

## Shot list (~60-90s total)

1. **Case list → create case** (~10s): show the empty case list, click
   "New Case", fill in examiner name, create it.
2. **Acquire evidence** (~10s): upload `ardupilot_sample.bin`, select
   platform `ardupilot`, show the SHA-256 hash appear.
3. **Analyze** (~10s): click analyze, show the event/track-point counts
   and the altitude-anomaly warning appear.
4. **Timeline + flight-path map tabs** (~15s): scroll the timeline, then
   switch to the map tab and show the flight path rendered with the
   anomaly points visible.
5. **Custody log tab** (~10s): show the hash-chained entries — call out
   that this is what `verify` re-checks.
6. **Report tab** (~15s): generate the report, show the embedded HTML
   report, click "Download PDF" to show the PDF export.
7. **(Optional, once implemented) Airspace tab**: show a no-fly-zone
   incursion flagged on the map, if that feature lands before recording.

## After recording

- [ ] Trim dead air at the start/end.
- [ ] Export at a resolution/bitrate that stays under whatever the
      submission portal's file-size limit is — re-encode with a lower
      bitrate rather than dropping resolution if it's too large.
- [ ] Do one full playback before submitting — confirm captions/audio are
      actually synced and readable at normal viewing size.
