import magic
from django.core.exceptions import ValidationError
import clamd
from django.conf import settings


# Validate file type using python magic and scan for virus using python clamd
def validate_file_type(upload):
    upload.seek(0)
    file_type = magic.from_buffer(upload.read(), mime=True)
    allowed_types = settings.ALLOWED_FILE_TYPES
    if file_type not in allowed_types.viewvalues():
        raise ValidationError('You cannot upload file type: {}. Allowed file types are: {}.'
                                  .format(str(file_type), ', '.join(allowed_types.viewkeys())))

    else:
        # setup unix socket and scan stream
        cd = clamd.ClamdNetworkSocket(settings.CLAMD_TCP_ADDR, settings.CLAMD_TCP_SOCKET)
        upload.seek(0)
        scan_results = cd.instream(upload)
        upload.seek(0)
        if (scan_results['stream'][0] == 'FOUND'):
            raise ValidationError("Your file appears to be infected by a virus.Please check again before uploading.")