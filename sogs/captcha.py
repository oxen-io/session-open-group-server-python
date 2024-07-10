from PIL import Image, ImageDraw
import random
import numpy as np


class Shape:
    def __init__(self, type, color, x1, y1, x2, y2):
        self.type = type
        self.color = color
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2

    def draw_shape(self, draw):
        if self.type == "rectangle":
            draw.rectangle(
                [self.x1, self.y1, self.x2, self.y2],
                outline="black",
                fill=self.color
            )
        elif self.type == "square":
            side = min(self.x2 - self.x1, self.y2 - self.y1)
            draw.rectangle(
                [self.x1, self.y1, self.x1 + side, self.y1 + side],
                outline="black",
                fill=self.color
            )
        elif self.type == "pentagon":
            draw.regular_polygon(
                [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2, min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                5,
                outline="black",
                fill=self.color
            )
        elif self.type == "hexagon":
            draw.regular_polygon(
                [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2, min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                6,
                outline="black",
                fill=self.color
            )
        elif self.type == "circle":
            draw.ellipse(
                [self.x1, self.y1, self.x2, self.y2],
                outline="black",
                fill=self.color
            )
        elif self.type == "triangle":
            draw.regular_polygon(
                [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2, min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                3,
                outline="black",
                fill=self.color
            )
        elif self.type == "octagon":
            draw.regular_polygon(
                [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2, min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                8,
                outline="black",
                fill=self.color
            )
        elif self.type == "oval":
            draw.ellipse(
                [self.x1, self.y1, self.x2, self.y2],
                outline="black",
                fill=self.color
            )

    def is_overlapping(self, shapes):
        for shape in shapes:
            distance = abs(self.x1 - shape.x1)
            print(distance, shape.x2 - shape.x1)
            if distance < (shape.x2 - shape.x1) / 3:
                return True
        return False


class Captcha:

    def __init__(self):
        self.question = "Combined how many green rectangles and red hexagons in the image?"
        self.answer = None
        # List of possible answer emojis
        self.answer_set = ["\u0030\ufe0f\u20e3", "\u0031\ufe0f\u20e3", "\u0032\ufe0f\u20e3", "\u0033\ufe0f\u20e3",
                           "\u0034\ufe0f\u20e3", "\u0035\ufe0f\u20e3", "\u0036\ufe0f\u20e3", "\u0037\ufe0f\u20e3",
                           "\u0038\ufe0f\u20e3", "\u0039\ufe0f\u20e3", "\U0001F51F"]
        # List of possible shapes
        self.shape_set = ["rectangle", "square", "pentagon", "hexagon", "circle", "triangle", "octagon", "oval"]
        # List of primary colors
        self.color_set = ["red", "green", "blue"]
        self.captcha_image = "shapes_image.png"
        self.generate_captcha(width=400, height=200)

    def generate_captcha(self, width, height):
        # Create a new image with white background
        image = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(image)

        # Precompute random colors
        random_colors = [random.choice(self.color_set) for _ in range(10)]
        shapes = []
        min_size_x = int(width * 0.1)
        min_size_y = int(height * 0.1)
        answer = 0
        # Draw 10 shapes randomly on the image
        while len(shapes) < 10:
            shape_type = random.choice(self.shape_set)
            color = random_colors[len(shapes) - 1]
            if shape_type == "rectangle" and color == "green" or shape_type == "hexagon" and color == "red":
                answer += 1
            x1 = random.randint(0, width - min_size_x)
            y1 = random.randint(0, height - min_size_y)
            x2 = x1 + random.randint(min_size_x, min(width - x1, int(width / 2)))
            y2 = y1 + random.randint(min_size_y, min(height - y1, int(height / 2)))
            shape = Shape(shape_type, color, x1, y1, x2, y2)
            if shape.is_overlapping(shapes):
                print("Overlapping")
                continue
            else:
                shapes.append(shape)
                shape.draw_shape(draw)

        # Save the image
        image.save("shapes_image.png")

        self.answer = self.answer_set[answer]


if __name__ == '__main__':
    captcha = Captcha()
    print(captcha.answer_set)