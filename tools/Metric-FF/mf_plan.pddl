
ff: parsing domain file
domain 'PAG' defined
 ... done.
ff: parsing problem file
problem 'PAG-PROBLEM1' defined
 ... done.


no metric specified.

ff: search configuration is best-first search.
Metric is plan length.
NO COST MINIMIZATION (and no cost-minimizing relaxed plans).

advancing to goal distance:   10
                               9
                               8
                               7
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: ATTACKER-SENDS-EMAIL-WITH-KEYLOGGER USER1 FILE-WITH-TROJAN KEY-LOGGER1
        1: USER-VISITS-SITE USER1 BROWSER-IE VBSCRIPT-LINK
        2: USER-STARTS-EMAIL USER1 GMAIL
        3: USER-READS-EMAIL USER1 GMAIL BAD-EMAIL
        4: USER-OPENS-ATTACHMENT USER1 BAD-EMAIL FILE-WITH-TROJAN GMAIL
        5: KEY-LOGGER-INSTALLED USER1 FILE-WITH-TROJAN KEY-LOGGER1
        6: USER-PRESSES-F1-AT-VBSCRIPT-SITE USER1 BROWSER-IE VBSCRIPT-LINK
        7: KEY-LOGGER-ACTIVATED KEY-LOGGER1 BROWSER-IE
        8: USER-LOGIN-WITH-KEYLOGGER-ACTIVATED USER1 ACCOUNT-BANK KEY-LOGGER1
        9: ATTACKER-INTERCEPTS KEY-LOGGER1 ACCOUNT-BANK

time spent:    0.00 seconds instantiating 578 easy, 0 hard action templates
               0.00 seconds reachability analysis, yielding 17 facts and 11 actions
               0.00 seconds creating final representation with 15 relevant facts, 0 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 28 states, to a max depth of 0
               0.00 seconds total time

