import pg from "pg";
import dotenv from "dotenv";

dotenv.config();
const pool = new pg.Pool({ max: 1 });
export default pool;
