Sysbox-deploy-k8s image generation and update procedure
=======================================================

1) Build the sysbox-deploy images through the usual `make <target>` method. The process
must be completed in every supported architecture (i.e., amd64 and arm64).

2) Identify the image that has been created and re-tag it accordingly to match the
platform architecture being used (this must be done for each supported platform):

```
$ docker images
REPOSITORY                           TAG       IMAGE ID       CREATED              SIZE
ghcr.io/nestybox/sysbox-deploy-k8s   v0.5.2    eb28ac89b60f   About a minute ago   982MB


$ docker tag eb28ac89b60f ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2_arm64

$ docker images
REPOSITORY                           TAG            IMAGE ID       CREATED          SIZE
ghcr.io/nestybox/sysbox-deploy-k8s   v0.5.2         eb28ac89b60f   7 minutes ago    982MB
ghcr.io/nestybox/sysbox-deploy-k8s   v0.5.2_arm64   eb28ac89b60f   7 minutes ago    982MB
```

3) Push each image to ghcr.io (for both supported platforms):

```
$ docker push ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2_arm64
```

4) Now is time to update the existing manifest to point to the new image components. This
step can be completed in any linux machine, doesn't need to be any of the ones previously
utilized to build the sysbox-deploy images.

  * We start by removing the current manifests (in case they are already present locally).

```
$ docker manifest rm ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2
$ docker manifest rm ghcr.io/nestybox/sysbox-deploy-k8s:latest
```

  * Now we recreate each manifest by pointing it to the platform-specific images previously
  created (which don't need to be present/fetched locally for this operation to succeed).

```
$ docker manifest create ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2 --amend ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2_amd64 --amend ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2_arm64
$ docker manifest create ghcr.io/nestybox/sysbox-deploy-k8s:latest --amend ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2_amd64 --amend ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2_arm64
```

 * Finally, we push the newly updated manifests to ghcr.io:

```
$ docker manifest push ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2
$ docker manifest push ghcr.io/nestybox/sysbox-deploy-k8s:latest
```

5) Verify in Github web-portal that the image-digests of both the manifest and the images
fully match those in our build-server:

  * Compare the image-digests seen below (the following two commands), with the ones seen at
  the Github packages' site:

```
$ docker images --digests | egrep "sysbox-deploy"
``

```
$ docker manifest inspect ghcr.io/nestybox/sysbox-deploy-k8s:v0.5.2
...

$ docker manifest inspect ghcr.io/nestybox/sysbox-deploy-k8s:latest
...

````



