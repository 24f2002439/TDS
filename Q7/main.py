import time
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# 1. Enforce strict CORS policy (No wildcards)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dash-3eka7s.example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Add Required Middleware Headers
@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    start_time = time.time()
    
    # Process the request
    response = await call_next(request)
    
    # Calculate process time and generate a unique UUID
    process_time = time.time() - start_time
    request_id = str(uuid.uuid4())
    
    # Attach the headers to the final response
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# 3. Create the /stats endpoint
@app.get("/stats")
def get_stats(values: str):
    # Convert the comma-separated string "1,2,3" into a list of integers [1, 2, 3]
    num_list = [int(v) for v in values.split(",")]
    
    count = len(num_list)
    total_sum = sum(num_list)
    
    return {
        "email": "24f2002439@ds.study.iitm.ac.in",
        "count": count,
        "sum": total_sum,
        "min": min(num_list),
        "max": max(num_list),
        "mean": total_sum / count
    }