import vt

from bot.config import VIRUSTOTAL_API_KEY


async def scan_vt_hash(file_hash: str) -> dict:
    async with vt.Client(VIRUSTOTAL_API_KEY) as client:
        try:
            file_obj = await client.get_object_async(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            results = getattr(file_obj, "last_analysis_results", {})

            def get_engine_status(engine_name: str) -> str:
                engine_data = results.get(engine_name, {})
                category = engine_data.get("category", "undetected")
                result = engine_data.get("result")
                if category == "malicious":
                    return f"Detected ({result})"
                if category == "suspicious":
                    return f"Suspicious ({result})"
                return "Clean"

            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "top_engines": {
                    "Microsoft": get_engine_status("Microsoft"),
                    "Kaspersky": get_engine_status("Kaspersky"),
                    "BitDefender": get_engine_status("BitDefender"),
                },
            }
        except vt.APIError as error:
            if error.code == "NotFoundError":
                return {"found": False, "error": "NotFound"}
            return {"found": False, "error": str(error)}