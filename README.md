# Alert Cherry-Picker

An algorithm written in Python 3.10 to pick the top 4 priority alerts based on keys and identifiers using a given template

## Usage/Examples

Pass the desired alert object into the find_priority_alerts function. An example of the alert object is included in the code.

## Approach

The approach taken iterates over the alerts rather than the priorities out of concern for no matches in the higher priorities given a longer list of alerts. Depending on the alert list size and order, there are certainly cases in which iterating over the priorities rather than the alerts would be more effective, but for broader use purposes the alerts were chosen as the prime iterable.

A dictionary (prioritized_alerts) is populated on the fly based on priority levels. Running deeper, the type, subtype and titles are scanned for matching values. Upon identifying that all three are successful matches, the prioritized_alerts dictionary is populated by the value according to the priority key.

Finally, after the dictionary is complete, a generator comprehension is used to flatten and return the final values. The itertools.islice function is in place to limit the need to iterate over an object that is already sorted, as only the first 4 ids are needed for the task at hand.
