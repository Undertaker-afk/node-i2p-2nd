# Reseed signer trust anchors

The PEM certificates in this directory are the I2P reseed signer certificates from PurpleI2P/i2pd, revision `4be508a882e672d3171c7a8d54af73bd32716777`, path `contrib/certificates/reseed/`:

https://github.com/PurpleI2P/i2pd/tree/4be508a882e672d3171c7a8d54af73bd32716777/contrib/certificates/reseed

They are used as pinned RSA public-key trust anchors to verify SU3 reseed signatures. The remote HTTPS certificate alone is not treated as sufficient authentication. Update these keys only from a trusted I2P distribution/source and review signer changes.
