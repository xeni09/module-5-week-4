const mongoose = require("mongoose");

const schema = new mongoose.Schema(
  {
    createdAt: {
      type: Date,
    },
    updatedAt: {
      type: Date,
    },
    title: {
      type: String,
      required: true,
      minlength: 6,
    },
    text: {
      type: String,
      required: true,
      minlength: 6,
    },
    author: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        ret.id = doc._id;
        delete ret.__v;
        delete ret._id;
        delete ret.password;

        return ret;
      },
    },
  }
);

module.exports = mongoose.model("Post", schema);
