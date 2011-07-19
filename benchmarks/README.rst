These benchmarks were performed by a Python cProfile profile on
bcrypt.hashpw, with a pre-generated salt, and the number of rounds
mentioned in the file name.

``v1`` and ``v2`` refer to iterations of the code base, beginning
with Michael Gilfix's original blowfish implementation, and
improving it step by step. These versions also exist as tags on the
git repository.
