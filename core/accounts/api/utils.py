import threading
from mail_templated import EmailMessage


class TemplateEmailThread(threading.Thread):
    """
    This class demonstrates how to send email in a separate thread (multiprocess at the same time)
    """

    def __init__(self, email_obj):
        self.email_obj = email_obj
        threading.Thread.__init__(self)

    def run(self):
        self.email_obj.send()


class Util:
    """
    This class sends emails using templated mail with templates and context variables
    if you want to attach files you should attach it after making email object using EmailMessage
    """

    @staticmethod
    def send_templated_email(template_path, data, subject, from_email, to):

        email = EmailMessage(
            template_name=template_path,
            context=data,
            subject=subject,
            from_email=from_email,
            to=[to],
        )
        TemplateEmailThread(email).start()
