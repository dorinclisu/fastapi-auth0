
import setuptools

with open('README.md', encoding='utf-8') as file:
    readme = file.read()

setuptools.setup(
    name='fastapi-auth0',
    version='0.5.0',
    description='Easy auth0.com integration for FastAPI',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/dorinclisu/fastapi-auth0',
    author='Dorin Clisu',
    license='MIT',
    packages=setuptools.find_packages('src'),
    package_dir={'': 'src'},
    package_data={'': ['py.typed']},
    python_requires='>=3.7',
    install_requires=['fastapi>=0.60.0', 'python-jose>=3.2.0']
)
