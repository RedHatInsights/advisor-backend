import json

from django.conf import settings
from django.core.management.base import BaseCommand
from drf_spectacular.generators import SchemaGenerator

from api.views.swagger import foreman_api_settings


SWAGGER_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Insights Advisor Foreman API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      spec: %s,
      dom_id: '#swagger-ui',
    });
  </script>
</body>
</html>
"""


class Command(BaseCommand):
    help = 'Generate a standalone Swagger HTML page for the Foreman API subset.'

    def add_arguments(self, parser):
        parser.add_argument(
            '-o', '--output', default='foreman_openapi.html',
            help='Output file path (default: foreman_openapi.html)',
        )
        parser.add_argument(
            '--json', action='store_true',
            help='Output raw OpenAPI JSON instead of HTML',
        )

    def handle(self, *args, **options):
        # Temporarily apply foreman-specific settings so the generator
        # picks up the right preprocessing/postprocessing hooks.
        original = settings.SPECTACULAR_SETTINGS.copy()
        settings.SPECTACULAR_SETTINGS.update(foreman_api_settings)
        try:
            generator = SchemaGenerator()
            schema = generator.get_schema(public=True)
        finally:
            settings.SPECTACULAR_SETTINGS = original

        spec_json = json.dumps(schema, indent=2, default=str)

        if options['json']:
            output = spec_json
        else:
            output = SWAGGER_UI_HTML % spec_json

        with open(options['output'], 'w') as f:
            f.write(output)

        self.stdout.write(self.style.SUCCESS(
            f"Written to {options['output']}"
        ))
