"""A chronological activity list is the reusable story/timeline layer."""


def generate_story(activities):
    ordered = sorted(activities, key=lambda item: (item["start_time"], item["id"]))
    for index, activity in enumerate(ordered, 1):
        activity["sequence"] = index
    return ordered
