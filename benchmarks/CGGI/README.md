## Benchmarking of CGGI Bootstrapping Algorithm

> The benchmarks have been run on a commodity desktop with a 12th Gen Intel(R) Core(TM) i5-1235U, 1300 Mhz and 16 GB of RAM, running Ubuntu 22.04.5 LTS.

### CGGI single-bit

We ran the benchmarks for CGGI (Chillotti-Gama-Georgieva-Izabachene) bootstrapping algorithm (with 1 bit precision) given in the openFHE library for c++ using the source file `binfhe-ginx.cpp`.

No. of slots: 1

bits of precision: 1

![cggi-1-bit](../../images/cggi-benchmarks-1.png)

### CGGI multi-bit

We ran the benchmarks for CGGI (Chillotti-Gama-Georgieva-Izabachene) bootstrapping algorithm (with 1 bit precision) given in the openFHE library for c++ using the source file `binfhe/examples/eval-function.cpp;`.

No. of slots: 1

bits of precision: 3

gen keys then evaluate x^3%p (p=8 in image below)

![cggi-multi-bit](../../images/cggi-benchmarks-2.png)
