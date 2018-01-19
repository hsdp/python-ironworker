import re
import os
import zipfile
import hashlib
import fnmatch


def zip_dir(source_dir, archive_file, fnmatch_list=None):
    """Creates an archive of the given directory and stores it in the given
    archive_file which may be a filename as well. By default, this function
    will look for a .cfignore file and exclude any matching entries from the
    archive.
    """
    if fnmatch_list is None:
        fnmatch_list = []

    cwd = os.getcwd()
    try:
        with zipfile.ZipFile(
                archive_file,
                mode='w',
                compression=zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isdir(source_dir):
                os.chdir(source_dir)
                files = list_files(source_dir, fnmatch_list)
                for f in files:
                    name = f['fn'].replace(source_dir, '')
                    compress = zipfile.ZIP_STORED if f['fn'].endswith(
                        '/') else zipfile.ZIP_DEFLATED
                    zipf.write(f['fn'], arcname=name, compress_type=compress)
            else:
                zipf.write(
                    source_dir,
                    arcname=os.path.basename(source_dir),
                    compress_type=zipfile.ZIP_DEFLATED)
    finally:
        os.chdir(cwd)

    return archive_file


def list_files(source_directory, fnmatch_list=None):
    """Lists files in the given directory and excludes files or directories that
    match any pattern in the fnmatch_list.
    """
    if fnmatch_list is None:
        fnmatch_list = []
    files = os.walk(source_directory)
    _files = []
    for dirname, subdirs, filenames in files:
        for d in subdirs:
            d = os.path.join(dirname, d)
            if not d.endswith('/'):
                d += '/'
            _files.append(d)

        for f in filenames:
            f = os.path.join(dirname, f)
            _files.append(f)

    if not source_directory.endswith('/'):
        source_directory += '/'

    files = []
    for f in _files:
        f = f.replace(source_directory, '')
        matches = True
        for pat in fnmatch_list:
            if fnmatch.fnmatch(f, pat) or f.startswith(pat):
                matches = False
                break
        if matches:
            files.append(dict(
                fn=f,
                sha1=file_sha1(f),
                size=file_size(f),
            ))

    return files


def file_sha1(filename):
    """Creates a SHA1 of the given file. This is useful in resource matching
    for uploading app bits.
    """
    if os.path.isdir(filename):
        return '0'
    with open(filename, 'r') as f:
        return hashlib.sha1(f.read()).hexdigest()


def file_size(filename):
    """Get the size of the given file. This is useful in resource matching
    for uploading app bits.
    """
    if os.path.isdir(filename):
        return 0
    return os.path.getsize(filename)


def parse_ignore_file(ignorefile, include_star=True):
    """Parses a .gitignore or .cfignore file for fnmatch patterns
    """
    if ignorefile is None:
        return []

    try:
        with open(ignorefile, 'r') as f:
            _cfignore = f.read().split('\n')

        cfignore = []
        for l in _cfignore:
            if l and not l.startswith('#'):
                l = re.sub('\s*#.*', '', l).strip()
                if include_star and l.endswith('/'):
                    l += '*'
                cfignore.append(l)
    except Exception as e:
        print(e)
        cfignore = []

    cfignore.extend(['.git/', '.gitignore', '.cfignore', 'manifest.yml'])

    return cfignore


if '__main__' == __name__:
    def main():
        import json
        import argparse

        args = argparse.ArgumentParser()
        args.add_argument('-i', dest='in_directory', required=True)
        args.add_argument('-I', dest='ignore_file', default='.gitignore')
        args.add_argument('-o', dest='out_file')
        args.add_argument('-l', dest='list_files', action='store_true')
        args = args.parse_args()

        in_dir = os.path.join(os.getcwd(), args.in_directory)
        ignore_file = os.path.join(os.getcwd(), args.ignore_file)
        ignores = parse_ignore_file(ignore_file)

        if args.list_files:
            print(json.dumps(list_files(in_dir, ignores)))
        else:
            out_file = os.path.join(os.getcwd(), args.out_file)
            print(zip_dir(in_dir, out_file, ignores))

    main()
