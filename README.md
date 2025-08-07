# How to run?

1. Make sure you have setup openfhe first : [installtion guide](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html)

2. After creating `build` directory :

```bash
cd build && make
```

3. As all the files for benchmarks are in place for CKKS and CGGI along with `console_reporter.cc`

You can run them on your own machine:

```bash
$~/LBP-FHE/openfhe-development/build$ bin/benchmark/ckks-sparse-packing 
```

```bash
$~/LBP-FHE/openfhe-development/build$ bin/benchmark/ckks-full-packing 
```
```bash
$~/LBP-FHE/openfhe-development/build$ bin/benchmark/cggi-eval-func 
```


