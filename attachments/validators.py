import magic
from django.core.exceptions import ValidationError
import clamd
from django import forms
from django.conf import settings

# Validate file type using python magic and
# scan for virus using python clamd


def validate_file_type(upload):
    upload.seek(0)

    # Get File type
    file_type = magic.from_buffer(upload.read(1024), mime=True)

    # Check if file type satisfies our types
    if hasattr(settings, 'ALLOWED_FILE_TYPES') and \
        file_type not in ALLOWED_FILE_TYPES:
            raise ValidationError(
                'You cannot upload ' + str(file_type) + ' file type. Allowed file types are: PDF, Microsoft word, Open Office docs and images (jpg or png).')

    else:
        # if file meets standard, scan for virus
        # https://stackoverflow.com/questions/50499161/setting-up-a-file-upload-stream-scan-using-clamav-in-a-django-back-end
        # setup unix socket to scan stream
        cd = clamd.ClamdUnixSocket()

        # scan stream
        scan_results = cd.instream(upload)

        if (scan_results == 'FOUND'):
            raise ValidationError(
                'Your file appears to be infected by a virus.Please check again before uploading.')
