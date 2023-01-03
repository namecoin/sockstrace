load("cirrus", "env", "http")

def on_build_failed(ctx):
    url = env.get("SLACK_WEBHOOK_URL")
    if not url:
        return

    message = {
        "text": "https://cirrus-ci.com/build/{} failed!".format(ctx.payload.data.build.id)
    }

    http.post(url, json_body=message)
