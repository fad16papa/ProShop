import express from "express";
import {
  getProducts,
  getProductById,
} from "../controllers/productController.js";

const router = express.Router();

//@desc:    This will fetch all the products
//@route:   GET /api/products
//@access:  Public
router.route("/").get(getProducts);

//@desc:    This will fetch single product by its ID
//@route:   GET /api/products/:id
//@access:  Public
router.route("/:id").get(getProductById);

export default router;
