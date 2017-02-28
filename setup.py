import setuptools


setuptools.setup(
    version="0.0.1",
    license='mit',
    name="py-azure",
    author='nathan todd-stone',
    author_email='me@nathants.com',
    url='http://github.com/nathants/py-azure',
    packages=['py_azure'],
    install_requires=['azure-cli==0.1.2rc2',
                      'pytz >2016, <2017',
                      'tzlocal >1, <2 ',
                      'pager >3, <4'],
    entry_points={'console_scripts': ['azc = py_azure.compute:main']},
    description='azure',
)
