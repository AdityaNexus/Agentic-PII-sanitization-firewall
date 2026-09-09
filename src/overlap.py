from .models import PIIDetection


class OverlapResolver:

    def resolve(
        self,
        detections: list[PIIDetection]
    ) -> list[PIIDetection]:

        if not detections:
            return []

        # Higher confidence first
        detections = sorted(
            detections,
            key=lambda d: d.score,
            reverse=True
        )

        selected: list[PIIDetection] = []

        for candidate in detections:

            overlaps = False

            for existing in selected:

                if (
                    candidate.start < existing.end
                    and candidate.end > existing.start
                ):
                    overlaps = True
                    break

            if not overlaps:
                selected.append(candidate)

        # Restore document order
        selected.sort(key=lambda d: d.start)

        return selected