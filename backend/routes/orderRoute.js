import express from "express";
const router = express.Router();
import { addOrderItems, getOrderById } from "../controllers/orderControlle.js";
import { protect } from "../middleware/authMiddleware.js";

router.route("/").post(protect, addOrderItems);
router.route("/:id").get(getOrderById);

export default router;
