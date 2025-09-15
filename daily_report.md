# Daily Incident Report

Generated: Mon Sep 15 11:44:42 2025

## Summary

- Total incidents: 7
- Unique IPs: 3
- Most common attack: failed_login (5 times)

- Block recommendations: 4 (57.1%)
- Monitor recommendations: 0 (0.0%)

### Incidents by Type

Type            Count
------------  -------
failed_login        5
port_scan           2

## Detailed Incidents

  ID  IP            Type            Count  First Seen                        Last Seen                         Country    City    Intel                              Recommendation
----  ------------  ------------  -------  --------------------------------  --------------------------------  ---------  ------  ---------------------------------  ----------------
   7  5.5.5.5       failed_login        5  2025-09-15T10:43:20.526993+00:00  2025-09-15T10:43:29.566070+00:00  DE         Kassel  VT_mal=1, VT_susp=0, AbuseScore=0  BLOCK
   6  5.5.5.5       failed_login        5  2025-09-15T09:05:35.688029+00:00  2025-09-15T09:05:39.704533+00:00  DE         Kassel  VT_mal=1, VT_susp=0, AbuseScore=0  BLOCK
   5  5.5.5.5       failed_login        5  2025-09-15T09:04:33.032800+00:00  2025-09-15T09:04:39.063584+00:00  DE         Kassel  VT_mal=1, VT_susp=0, AbuseScore=0  BLOCK
   4  5.5.5.5       failed_login        5  2025-09-15T08:57:01.289414+00:00  2025-09-15T08:57:23.378687+00:00  DE         Kassel  VT_mal=1, VT_susp=0, AbuseScore=0  BLOCK
   3  unknown       port_scan           1  2025-09-09T14:11:47.728583+00:00  2025-09-09T14:11:47.728583+00:00  N/A        N/A     VT_mal=0, VT_susp=0, AbuseScore=0  ALLOW
   2  unknown       port_scan           1  2025-09-09T13:18:43.817439+00:00  2025-09-09T13:18:43.817439+00:00  N/A        N/A     VT_mal=0, VT_susp=0, AbuseScore=0  ALLOW
   1  192.168.1.50  failed_login        5  2025-09-09T13:16:17.223391+00:00  2025-09-09T13:16:51.380195+00:00  N/A        N/A     VT_mal=0, VT_susp=0, AbuseScore=0  ALLOW

## Top Malicious IPs

IP         VT Malicious    AbuseIPDB Score  Country    Last Seen
-------  --------------  -----------------  ---------  --------------------------------
5.5.5.5               1                  0  DE         2025-09-15T10:43:29.566070+00:00
5.5.5.5               1                  0  DE         2025-09-15T09:05:39.704533+00:00
5.5.5.5               1                  0  DE         2025-09-15T09:04:39.063584+00:00
5.5.5.5               1                  0  DE         2025-09-15T08:57:23.378687+00:00

## Narrative Summaries

**5.5.5.5** (DE)  
- Intel: VT_mal=1, VT_susp=0, AbuseScore=0  
- Recommendation: BLOCK

**5.5.5.5** (DE)  
- Intel: VT_mal=1, VT_susp=0, AbuseScore=0  
- Recommendation: BLOCK

**5.5.5.5** (DE)  
- Intel: VT_mal=1, VT_susp=0, AbuseScore=0  
- Recommendation: BLOCK

**5.5.5.5** (DE)  
- Intel: VT_mal=1, VT_susp=0, AbuseScore=0  
- Recommendation: BLOCK
