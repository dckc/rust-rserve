# cribbed from rserve-js
# https://github.com/cscheid/rserve-js/blob/develop/tests/r_files/oc_start.R

debug <- FALSE # isTRUE(nzchar(Sys.getenv("DEBUG")))
Rserve::Rserve(debug,
               args=c("--RS-conf", "oc.conf",
                      "--RS-source", "oc.init.R",
                      "--vanilla", "--no-save", "--quiet"))
