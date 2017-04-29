# dmprof - A *D*inky *M*emory *Prof*iler

Usage:

``` shell
$ make
$ ./dmprof
```

This should produce a `leaky.dmprof` log file. You can then process the log file to get meaning full data with,

``` shell
$ tools/report.pl leaky.dmprof > dmprof.report
```

