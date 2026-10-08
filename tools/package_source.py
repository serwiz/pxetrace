"""Build a source-only archive; never recursively include the workspace."""
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parent.parent
FIXED = ('README.md', 'EXPLANATION.md', 'LICENSE', 'pyproject.toml', '.gitignore',
         'tools/package_source.py', '.github/workflows/tests.yml')


def package_source(destination: Path) -> int:
    paths = [ROOT / name for name in FIXED]
    paths.extend(sorted((ROOT / 'pxetrace').glob('*.py')))
    paths.extend(sorted((ROOT / 'tests').glob('test_*.py')))
    for path in paths:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise ValueError(f'Fichier source absent ou lien interdit : {path.name}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, 'x:gz') as archive:
        for path in paths:
            info = archive.gettarinfo(str(path), arcname='pxetrace/' + path.relative_to(ROOT).as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mode = 0o644
            with path.open('rb') as stream:
                archive.addfile(info, stream)
    return len(paths)


if __name__ == '__main__':
    destination = ROOT / 'dist' / 'pxetrace-source.tar.gz'
    count = package_source(destination)
    print(f'{count} fichiers source : {destination}')
