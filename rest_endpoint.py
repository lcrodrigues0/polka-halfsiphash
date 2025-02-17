from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/")
async def root(request: Request):
    json_data = await request.json()
    print(json_data)  # Print JSON data to stdout
    return json_data
