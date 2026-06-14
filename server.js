const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.post("/generate-story", (req, res) => {

    const concept = req.body.concept;

    const story = {
        title: `The Story of ${concept}`,
        scenes: [
            {
                title: "Introduction",
                desc: `${concept} begins here`
            },
            {
                title: "Visualization",
                desc: `Understanding ${concept}`
            }
        ]
    };

    res.json(story);
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
