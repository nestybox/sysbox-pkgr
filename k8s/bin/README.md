# Sysbox-deploy Binaries Generation Tips

## CRI-O binaries

1. Clone CRI-O repository:

```
$ git clone git@github.com:nestybox/cri-o.git

$ cd cri-o
```

2. Switch to a local branch based off of the desired CRI-O release (i.e. currently v1.20
   or v1.21):

```
$ git checkout -b v1.21-sysbox origin/v1.21-sysbox
```

3. Build a 'static' version of the cri-o binary -- note that it takes a while, but it's
   just ~4MB larger than the regular binary:

```
$ CONTAINER_RUNTIME=docker make build-static
```

4. Copy the obtained binary to its expected location:

```
$ tree k8s/bin/crio
k8s/bin/crio
├── README.md
├── v1.20
│   └── crio
└── v1.21
    └── crio
```

## Flatcar binaries

<TBD>
