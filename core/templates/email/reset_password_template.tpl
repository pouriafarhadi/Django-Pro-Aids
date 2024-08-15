{% extends "mail_templated/base.tpl" %}
{% block subject %}Reset Password Request{% endblock %}

{% block html %}
<h2>Hello {{email}}</h2>
<p>Use the link below to reset your account password:</p>
<a>{{link}}</a>

<hr>
<small>best regards</small>
<small>{{site}}</small>
{% endblock %}