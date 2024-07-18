from PIL import Image, ImageDraw, ImageFont
import random
import emoji


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


class Captcha:

    FONT_PATH = 'NotoColorEmoji.ttf'
    # Bitmap fonts don't support scaling with freetype, so you must specify a valid size,
    # which is 109 for Noto Color Emoji.
    FONT_SIZE = 109
    EMOJI_LIST = {emoji_str for emoji_str, names in emoji.EMOJI_DATA.items() if 'skin_tone' not in str(names['en'])}
    WIDTH = 400
    HEIGHT = 200

    def __init__(self):
        self.question = "Please react with the emoji in the picture."
        self.answer = random.choice(list(Captcha.EMOJI_LIST))
        # List of possible shapes
        self.shape_set = ["rectangle", "square", "pentagon", "hexagon", "circle", "triangle", "octagon", "oval"]
        # List of primary colors
        self.color_set = ["red", "green", "blue", "orange", "yellow"]
        self.captcha_image = "shapes_image.png"
        self.generate_captcha(width=Captcha.WIDTH, height=Captcha.HEIGHT)

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
            x1 = random.randint(0, width - min_size_x)
            y1 = random.randint(0, height - min_size_y)
            x2 = x1 + random.randint(min_size_x, min(width - x1, int(width / 2)))
            y2 = y1 + random.randint(min_size_y, min(height - y1, int(height / 2)))
            shape = Shape(shape_type, color, x1, y1, x2, y2)
            shapes.append(shape)
            shape.draw_shape(draw)

        emoji_x = random.randint(0, width - Captcha.FONT_SIZE)
        emoji_y = random.randint(0, height - Captcha.FONT_SIZE)
        draw.text(
            (emoji_x, emoji_y),
            self.answer,
            font=ImageFont.truetype(Captcha.FONT_PATH, Captcha.FONT_SIZE),
            fill="black"
        )

        # Save the image
        image.save(self.captcha_image)

    def refresh(self):
        self.answer = random.choice(list(Captcha.EMOJI_LIST))
        self.generate_captcha(width=Captcha.WIDTH, height=Captcha.HEIGHT)


if __name__ == '__main__':
    captcha = Captcha()
    print(captcha.answer)
    print(Captcha.EMOJI_LIST)
